const serviceForHost = (host, env) => {
  const normalized = host.toLowerCase();
  if (normalized === env.API_HOST.toLowerCase()) return env.BACKEND_ORIGIN;
  if (normalized === env.ADMIN_HOST.toLowerCase()) return env.ADMIN_ORIGIN;
  if (normalized === env.FRONTEND_HOST.toLowerCase()) return env.FRONTEND_ORIGIN;
  return null;
};

export default {
  async fetch(request, env) {
    const required = ["ORIGIN_SECRET", "FRONTEND_HOST", "ADMIN_HOST", "API_HOST", "FRONTEND_ORIGIN", "ADMIN_ORIGIN", "BACKEND_ORIGIN"];
    if (required.some((name) => typeof env[name] !== "string" || !env[name]) || env.ORIGIN_SECRET.length < 32) return new Response("Proxy is not configured", { status: 503 });
    const incoming = new URL(request.url);
    const targetOrigin = serviceForHost(incoming.hostname, env);
    if (!targetOrigin) return new Response("Unknown host", { status: 421 });

    let target;
    try {
      target = new URL(targetOrigin);
      const allowedProvider = incoming.hostname.toLowerCase() === env.API_HOST.toLowerCase()
        ? target.hostname.endsWith(".up.railway.app")
        : target.hostname.endsWith(".vercel.app");
      if (target.protocol !== "https:" || !allowedProvider) return new Response("Invalid upstream", { status: 503 });
    } catch {
      return new Response("Invalid upstream", { status: 503 });
    }
    target.pathname = incoming.pathname;
    target.search = incoming.search;

    const headers = new Headers(request.headers);
    headers.delete("x-fonduz-origin");
    headers.set("X-FondUz-Origin", env.ORIGIN_SECRET);
    headers.set("X-Forwarded-Host", incoming.host);
    headers.set("X-Forwarded-Proto", "https");
    const upstreamRequest = new Request(target, new Request(request, { headers }));
    return fetch(upstreamRequest, { cf: { cacheTtl: 0, cacheEverything: false } });
  },
};
