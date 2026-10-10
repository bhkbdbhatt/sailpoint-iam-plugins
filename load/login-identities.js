// k6 load test matching the M6 plan scenario:
//   login + GET /identities + GET /stats/overview
//
// Run:
//   k6 run --vus 20 --duration 60s load/login-identities.js
//
// Adjust BASE_URL / credentials per environment. The p95 latency target
// (the M6 load gate) is encoded in `thresholds`; the run FAILS when it is
// exceeded.
import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: __ENV.VUS ? parseInt(__ENV.VUS, 10) : 20,
  duration: __ENV.DURATION || "60s",
  thresholds: {
    http_req_duration: ["p(95)<150"], // ms
    http_req_failed: ["rate<0.01"],
  },
};

const BASE_URL = __ENV.BASE_URL || "http://127.0.0.1:8080";

function login() {
  const res = http.post(
    `${BASE_URL}/v1/auth/login`,
    JSON.stringify({
      email: __ENV.EMAIL || "owner@example.com",
      password: __ENV.PASSWORD || "supersecret123",
    }),
    { headers: { "Content-Type": "application/json" } },
  );
  check(res, { "login 2xx": (r) => r.status >= 200 && r.status < 300 });
  return res.json("token");
}

export default function () {
  const token = login();
  const params = { headers: { Authorization: `Bearer ${token}` } };

  const identities = http.get(`${BASE_URL}/v1/identities`, params);
  check(identities, { "identities 2xx": (r) => r.status === 200 });

  const stats = http.get(`${BASE_URL}/v1/stats/overview`, params);
  check(stats, { "stats 2xx": (r) => r.status === 200 });
}