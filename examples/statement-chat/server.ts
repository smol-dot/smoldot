// Minimal static file server with COOP/COEP headers for SharedArrayBuffer
const server = Bun.serve({
  port: process.env.PORT ? parseInt(process.env.PORT) : 5173,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname === "/" ? "/index.html" : url.pathname;

    // Try current directory first, then public/
    let file = Bun.file("." + path);
    if (!(await file.exists())) {
      file = Bun.file("./public" + path);
    }

    if (await file.exists()) {
      return new Response(file, {
        headers: {
          "Cross-Origin-Opener-Policy": "same-origin",
          "Cross-Origin-Embedder-Policy": "require-corp",
        },
      });
    }
    return new Response("Not Found", { status: 404 });
  },
});

console.log(`Server: http://localhost:${server.port}/`);
