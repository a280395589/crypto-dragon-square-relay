# Crypto Dragon Square relay

This minimal publisher runs one server-authorized Binance Square job. It contains no application database, private application source, account credentials, or draft content.

Only manually dispatched jobs on the trusted source tag are enabled. The default operation is a read-only connectivity probe. Publishing requires authenticated claim and one-time arm responses from the project's separate gateway. A timeout, HTTP 504, or missing post ID is UNKNOWN and is never blindly retried. Only result acknowledgement may be retried.

The workflow uses standard Ubuntu runners in this public repository, with a five-minute timeout, read-only repository permission, no cache and no uploaded artifacts.

Secrets are configured separately through GitHub Actions Secrets. Never put them in workflow inputs, source files, logs, screenshots, issues, or job summaries.
