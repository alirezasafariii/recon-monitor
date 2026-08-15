from .base import (
    FAMILY_SPEC_FRAMEWORK_VERSION,
    FamilyDetectionSpec,
    FamilyStandardSpec,
    MethodologyStep,
    WriteupLesson,
    compose_detection_spec,
)
from .broken_function_authorization import BFLA_STANDARD_SPEC
from .broken_object_authorization import BOLA_STANDARD_SPEC
from .cors_misconfiguration import CORS_MISCONFIGURATION_STANDARD_SPEC
from .dom_xss import DOM_XSS_STANDARD_SPEC
from .file_upload import FILE_UPLOAD_STANDARD_SPEC
from .knowledge_projection import (
    KNOWLEDGE_PROJECTION_VERSION,
    family_knowledge_projection,
    standard_knowledge_projection,
    taxonomy_projection,
    validate_knowledge_projection,
    writeup_knowledge_projection,
)
from .mass_assignment import MASS_ASSIGNMENT_STANDARD_SPEC
from .path_traversal import PATH_TRAVERSAL_STANDARD_SPEC
from .sql_injection import SQL_INJECTION_STANDARD_SPEC
from .authentication_session import AUTHENTICATION_SESSION_STANDARD_SPEC
from .open_redirect import OPEN_REDIRECT_STANDARD_SPEC
from .postmessage_trust import POSTMESSAGE_TRUST_STANDARD_SPEC
from .graphql_authorization import GRAPHQL_AUTHORIZATION_STANDARD_SPEC
from .ssrf import SSRF_STANDARD_SPEC
from .registry import (
    FAMILY_DETECTION_SPECS,
    FAMILY_SPEC_REGISTRY_VERSION,
    FAMILY_STANDARD_SPECS,
    MIGRATED_FAMILIES,
    get_detection_spec,
    get_standard_spec,
    registry_status,
    validate_family_spec_registry,
)

__all__ = [name for name in globals() if not name.startswith("_")]
