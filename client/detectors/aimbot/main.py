"""
main.py
Sensor -> Detector -> 화면 출력까지 실제로 연결해서 돌리는 진입점.

흐름:
  MECCHA Telemetry (UE4SS가 남긴 JSONL)
        -> MecchaAimTelemetrySensor
        -> ShotEvent / confirmed outcome
        -> AimbotDetector.ingest_event()
        -> DetectionResult(dict)
        -> main.py가 화면에 출력
"""

import argparse
import json
import signal
import sys
import time
from pathlib import Path

# When launched as ``python client/detectors/aimbot/main.py``, Python puts
# this script's directory on sys.path, not the repository root where shared/ lives.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detector.aimbot_detector import AimbotDetector
from sensors.meccha_aim_telemetry_sensor import MecchaAimTelemetrySensor
from shared.config import ClientConfig
from shared.errors import SharedError
from shared.logger import (
    configure_client,
    flush_client,
    send_detection,
    shutdown_client,
)

DEFAULT_LOG_PATH = Path(
    r"C:\Program Files (x86)\Steam\steamapps\common\MECCHA CHAMELEON"
    r"\Chameleon\Binaries\Win64\ue4ss\Mods\DamageLogger"
    r"\meccha_aim_telemetry.jsonl"
)
POLL_SECONDS = 0.1


def parse_args():
    parser = argparse.ArgumentParser(description="MECCHA aimbot telemetry detector")
    parser.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="main.lua가 기록하는 meccha_aim_telemetry.jsonl 경로",
    )
    # 런처가 넘기는 세션·PC 식별자. 없으면(직접 실행) 예전처럼 UE 값 그대로 낸다.
    parser.add_argument("--session-id", help="런처 세션 id. 결과의 session_id 로 쓴다")
    parser.add_argument("--player-id", help="런처가 정한 이 PC 의 id. 결과의 player_id 로 쓴다")
    parser.add_argument(
        "--t0",
        type=float,
        help="런처 세션 시작 Unix epoch(초). 지정하면 출력 timestamp_ms를 이 시점 기준으로 맞춘다.",
    )
    parser.add_argument(
        "--from-end",
        action="store_true",
        help="시작할 때 파일에 이미 있는 기록은 건너뛴다(런처용). 이전 게임 기록이 "
             "지금 세션 이름으로 나가지 않게 한다",
    )
    return parser.parse_args()


def to_launcher_ids(result, session_id=None, player_id=None):
    """탐지 결과의 식별자를 런처 값으로 바꾸고, 원래 UE 값은 evidence 에 옮긴다.

    탐지기는 player_id 에 UE 액터 전체 경로(GetFullName)를 넣는다. 180자 안팎에
    공백·'/'·':' 이 들어가 shared 형식(짧은 안전 문자열, 128자까지)을 못 넘어서
    send_detection() 이 로컬에서 거절한다. 게다가 라운드마다 캐릭터가 다시 생겨
    한 세션 안에서도 값이 여러 개로 갈린다. 그래서 중앙에는 런처가 정한 PC id 를
    쓰고, 액터 경로는 evidence.source_attacker_id 로 남긴다(추적용).
    session_id 도 같다 — UE 쪽 세션 id 는 evidence.source_session_id 로 옮기고
    런처 세션을 써야 다른 모듈 결과와 같은 세션으로 묶인다.

    이 PC 의 것으로 보는 근거와 한계:
      점수가 붙는 신호는 전부 발사 기록(shot_attempt)이 있어야 나온다(신호 12 의
      +3 은 조준 궤적도 확정 처치도 필요 없고 발사 3건이면 된다). 발사 기록은
      SpawnShotEffect(Local) 에서 오고, 조준 후보·시야 판정은 이 PC 의 로컬
      컨트롤러로 계산된다. 그래서 이 PC 의 결과로 본다.
      #43 부터 Lua 가 쏜 사람이 이 PC 의 pawn 인지(is_local) 기록하고, 센서가
      is_local=false 를 뺀다. 남은 점: 로컬 컨트롤러를 UEHelpers.GetPlayerController
      로 얻는데, 이 함수는 로컬 여부를 사실상 안 보고 첫 PlayerController 를 준다.
      리슨서버 호스트에는 원격 클라이언트용 컨트롤러도 있어서, 호스트 PC 에서는
      비교 기준이 틀어질 수 있다(9/30 코드 확인, 게임 안 실측 전). 원래 액터 경로를
      evidence.source_attacker_id 에 남기는 것은 그런 경우를 나중에 가려내기 위해서다.

    탐지 로직·점수·reasons 는 건드리지 않는다. 원본 dict 도 바꾸지 않는다.
    """
    if not session_id and not player_id:
        return result
    out = dict(result)
    evidence = dict(out.get("evidence") or {})
    if player_id:
        evidence.setdefault("source_attacker_id", out.get("player_id"))
        out["player_id"] = player_id
    if session_id:
        evidence.setdefault("source_session_id", out.get("session_id"))
        out["session_id"] = session_id
    out["evidence"] = evidence
    return out


class LauncherTimeline:
    """UE 게임 시계를 런처 세션 시계로 평행이동한다.

    첫 UE4SS 원본 이벤트가 실제로 관찰된 시각을 런처의 ``t0`` 기준으로
    고정한다. 이후에는 UE 시계의 밀리초 간격을 그대로 보존한다.

    UE 시계가 새로 시작되면 기준을 다시 잡는다. 모드가 다시 로드되면 텔레메트리
    파일이 새로 쓰이고(UE 세션 id 가 바뀐다), 월드가 바뀌면 게임 시계가 0 부터
    다시 셀 수 있다. 예전 기준을 그대로 쓰면 시간이 크게 앞당겨지고, 음수가 되면
    shared 가 로컬에서 거절한다(9/30 재현: 새로 쓴 19건 중 3건 거절, 나머지는
    약 8초 이르게 찍힘).
    """

    # 같은 UE 세션 안에서 이만큼 넘게 거꾸로 가면 시계가 새로 시작된 것으로 본다.
    # 같은 순간에 기록되는 발사·처치 사이의 작은 역전까지 재기준으로 보지 않게 한다.
    RESTART_BACKWARD_MS = 1000

    def __init__(self, t0: float | None):
        self.t0 = t0
        self._offset_ms: int | None = None
        self._source_session = None
        self._last_source_ms: int | None = None
        self.rebased = 0

    def align(self, event) -> None:
        if self.t0 is None:
            return

        source_ms = event.timestamp_ms
        session = getattr(event, "session_id", None)
        restarted = self._offset_ms is not None and (
            session != self._source_session
            or source_ms < self._last_source_ms - self.RESTART_BACKWARD_MS
        )
        if self._offset_ms is None or restarted:
            observed_ms = round((time.time() - self.t0) * 1000)
            self._offset_ms = observed_ms - source_ms
            self._last_source_ms = source_ms
            if restarted:
                self.rebased += 1
                print(f"[INFO] UE clock restarted (session {session}); "
                      f"re-anchored launcher timeline ({self.rebased})")
        else:
            self._last_source_ms = max(self._last_source_ms, source_ms)
        self._source_session = session

        event.source_timestamp_ms = source_ms
        # 기준을 다시 잡으면 음수는 나오지 않지만, shared 가 음수를 거절하므로 막아 둔다.
        event.timestamp_ms = max(0, source_ms + self._offset_ms)


def main():
    # 런처는 끌 때 Ctrl+Break를 보낸다. 윈도 기본 처리는 즉시 종료라 아래 finally의
    # flush/shutdown이 안 돈다. KeyboardInterrupt로 바꿔 둔다.
    # 참고: client/Launcher/README.md "끌 때 정리 코드가 돌게 하려면 — 한 줄"
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, signal.default_int_handler)
    args = parse_args()
    print("=" * 50)
    print("MECCHA CHAMELEON - Aimbot Anti-Cheat")
    print("=" * 50)
    print(f"[INFO] Telemetry path: {args.log_path}")
    print("[INFO] Waiting for MECCHA telemetry...")

    sensor = MecchaAimTelemetrySensor(args.log_path)
    detector = AimbotDetector()
    timeline = LauncherTimeline(args.t0)
    if args.from_end:
        skipped = sensor.skip_existing()
        print(f"[INFO] Skipped {skipped} bytes already in the telemetry log (--from-end).")

    client_configured = False
    try:
        configure_client(ClientConfig.from_env())
        client_configured = True
        print("[INFO] Shared telemetry client configured.")
    except SharedError as exc:
        # 중앙 전송 설정이 없거나 잘못돼도 로컬 탐지는 계속한다.
        print(
            f"[WARNING] Shared telemetry is unavailable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

    print("[INFO] Telemetry connected.")
    print("[INFO] Aimbot detection started.")
    print("[INFO] Press Ctrl+C to stop.\n")

    try:
        while True:
            for event in sensor.read_events():
                timeline.align(event)
                result = detector.ingest_event(event)
                if result:
                    result = to_launcher_ids(result, args.session_id, args.player_id)
                    print("-" * 60)
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    if client_configured and result["raw_score"] > 0:
                        try:
                            receipt = send_detection(result)
                            # 'queued'는 로컬 outbox에 저장됐다는 뜻이며,
                            # 중앙 서버가 수신했다는 확인 응답은 아니다.
                            print(f"[INFO] Shared telemetry queued: {receipt.event_id}")
                        except SharedError as exc:
                            print(
                                f"[WARNING] Shared telemetry rejected locally: "
                                f"{type(exc).__name__}: {exc}",
                                file=sys.stderr,
                            )
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\n종료.")
    finally:
        if client_configured:
            try:
                flushed = flush_client(timeout=3)
                if not flushed:
                    print(
                        "[WARNING] Shared telemetry flush incomplete; pending or failed events remain.",
                        file=sys.stderr,
                    )
            except SharedError as exc:
                print(
                    f"[WARNING] Shared telemetry flush failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )

            try:
                stopped = shutdown_client(timeout=5)
                if not stopped:
                    print(
                        "[WARNING] Shared telemetry sender did not stop before timeout; "
                        "queued data remains in the outbox.",
                        file=sys.stderr,
                    )
            except SharedError as exc:
                print(
                    f"[WARNING] Shared telemetry shutdown failed: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    main()
