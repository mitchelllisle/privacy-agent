import os

import uvicorn


def main() -> None:
    """Run the FastAPI app with a configurable port.

    Reads the `PORT` environment variable and starts Uvicorn bound to all
    interfaces.
    """
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("privacyagent.app:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
