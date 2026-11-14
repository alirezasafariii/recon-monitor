# XSS observation analysis

The analyzer consumes stored observations through the existing family details
envelope. It does not launch a browser or send target traffic. Reflected, stored
and DOM XSS retain separate evidence requirements.

## Reflected and stored captures

Supply `reflected_xss_observations` or `stored_xss_observations` as a list of
records. Structured capture fields are:

| Field | Meaning |
| --- | --- |
| `marker` | Inert unique marker, 12–128 ASCII letters, numbers, `_` or `-` |
| `input_marker`, `input_name` | Exact source marker and input name |
| `request_id`, `request_url` | Stored request identifier and exact analyzed endpoint |
| `response_url`, `content_type`, `response_text` | Stored response; at most 1 MiB UTF-8 |
| `write_request_id`, `write_marker` | Separate write capture and its marker, for Stored |
| `read_request_contains_marker` | Must explicitly be false to establish persistence |

The response origin must match the analyzed endpoint. HTML contexts are
reported as HTML text, attribute, script, style, comment, textarea or title.
JSON, plain text, absent markers, incomplete captures and foreign-origin
responses do not establish an HTML reflection. HTML reflection and even a
marker in a script element establish context only, never execution.

Stored context additionally requires a different write request ID, the matching
write marker and an explicit marker-free read request. A marker merely echoed
from the current read request is insufficient evidence of persistence.

Existing stored browser execution evidence may provide
`reflected_script_execution_observed` or `stored_script_execution_observed`.
Structured captures additionally require `execution_marker` equal to the source
marker, a `browser_capture_id`, matching-origin `execution_url`, and explicit
controlled/authorized and benign-test flags. These are capture assertions, not
cryptographic verification of an external browser. Producers must attach actual
stored evidence; the analyzer does not synthesize browser execution evidence.
Legacy canonical signal envelopes remain compatible.

Encoding, sanitization or execution-blocking observations in the same record
prevent its conflicting execution claim from becoming direct evidence. Context
and missing evidence remain available for investigation. The analyzer output
includes bounded context summaries, not response bodies or marker values.

## DOM

Static source/sink proximity remains a hypothesis. Runtime sink reachability
alone is insufficient. Direct condition evidence requires an identified source,
a dangerous execution context and explicitly absent neutralization. A record
that simultaneously claims effective sanitization and absent sanitization cannot
establish the condition. This readiness metadata does not confirm a finding;
the existing analyst decision workflow remains responsible for confirmation.

## Verification

```bash
python -m unittest discover -s tests -p 'test_xss_observation_logic.py' -v
```
