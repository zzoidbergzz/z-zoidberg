from strawberry.extensions import Extension


class TenantExtension(Extension):
    """Inject tenant context into GraphQL requests."""

    async def on_executing_start(self):
        request = self.execution_context.context.get("request")
        if request:
            tenant = request.state.__dict__.get("tenant_id")
            self.execution_context.context["tenant_id"] = tenant
