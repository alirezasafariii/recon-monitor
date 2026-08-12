from .base import make_spec, writeup
SPEC = make_spec(
    family="cryptographic_failure",
    strategy="cryptographic_control_failure",
    surface_terms=("tls", "ssl", "cipher", "crypto", "encrypt", "decrypt", "hash", "md5", "sha1", "random", "nonce", "iv", "key"),
    surface_fields=("cipher", "algorithm", "key", "nonce", "iv", "tls_version", "signature", "hash"),
    confounders=("security_misconfiguration", "authentication_session", "secret_exposure", "sensitive_caching"),
    expected_wstg=("WSTG-CRYP-01",),
    expected_cwe=("CWE-319", "CWE-327", "CWE-338", "CWE-757"),
    writeups=(writeup(
        "GHSL-2021-1012 / keypair weak randomness duplicate RSA keys",
        "https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/",
        "exact",
        "Crypto API names are not findings; decisive evidence is an actually weak algorithm, predictable randomness, key reuse, downgrade, or plaintext handling of sensitive data.",
    ),),
)
