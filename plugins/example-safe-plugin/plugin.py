class ExamplePlugin:
    metadata = {"name": "example-safe-plugin", "version": "1.0.0", "category": "analysis"}
    def healthcheck(self): return True, "ok"
    def plan(self, context): return {"network_requests": 0, "target": context.get("target", "")}
    def execute(self, context): return {"ok": True, "message": "example plugin executed", "target": context.get("target", "")}
plugin = ExamplePlugin()
