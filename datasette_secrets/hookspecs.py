from pluggy import HookspecMarker

hookspec = HookspecMarker("datasette")


@hookspec
def register_secrets(datasette):
    "Return a list of Secret instances, or an awaitable function returning that list"
