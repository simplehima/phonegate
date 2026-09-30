Place extra root CA certificates here (PEM, `*.crt`) **only** if your network intercepts TLS
(e.g. corporate proxies such as Sophos/Zscaler). They are trusted only during the image build so
`cargo` can download crates. Files here are git-ignored; never commit them.
