// daemon/test/fixtures/shutdown-dispose-failure.mjs
//
// daemon.js를 기동하되, 세션 풀의 shutdown이 반드시 실패하도록
// prototype을 먼저 바꿔치기한 뒤 SIGTERM 경로를 태운다.

// daemon.js가 import할 바로 그 클래스를 먼저 가져온다.
import { SessionPool } from "../../src/session-pool.js";

SessionPool.prototype.shutdown = () =>
  Promise.reject(new Error("injected dispose failure"));

// daemon이 등록할 SIGTERM/SIGINT 핸들러를 가로채 붙잡아 둔다.
const signalHandlers = new Map();
const originalProcessOn = process.on;
process.on = function captureSignalHandler(event, handler) {
  if (event === "SIGTERM" || event === "SIGINT") {
    signalHandlers.set(event, handler);
    return this;
  }
  return originalProcessOn.call(this, event, handler);
};

// prototype 조작 후 daemon을 기동한다.
await import("../../src/daemon.js");
process.on = originalProcessOn;

// 운영자의 서비스 정지를 재현한다. Windows에서도 실제 signal 없이 실행된다.
setTimeout(() => signalHandlers.get("SIGTERM")(), 100);
