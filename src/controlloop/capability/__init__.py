"""What an agent can really do: effective authority, direct capability
paths, bounded transitive capability paths, a material capability
taxonomy, and a blast-radius statement naming the single worst
reachable action, computed from already-discovered ACBOM evidence."""

from controlloop.capability.blast_radius import (
    CURRENT_BLAST_RADIUS_SCHEMA_VERSION,
    BlastRadiusStatement,
    compute_blast_radius,
    describe_blast_radius,
)
from controlloop.capability.compute import (
    compute_direct_capability_paths,
    compute_effective_authority,
    compute_transitive_capability_paths,
    effective_authority_digest,
)
from controlloop.capability.models import (
    CURRENT_CAPABILITY_SCHEMA_VERSION,
    CapabilityPath,
    EffectiveAuthorityEntry,
    PathHop,
)
from controlloop.capability.taxonomy import (
    MATERIAL_CAPABILITY_TAXONOMY_VERSION,
    MaterialCapabilityClass,
    classify_material_capability,
    worst_class,
)

__all__ = [
    "CURRENT_BLAST_RADIUS_SCHEMA_VERSION",
    "CURRENT_CAPABILITY_SCHEMA_VERSION",
    "MATERIAL_CAPABILITY_TAXONOMY_VERSION",
    "BlastRadiusStatement",
    "CapabilityPath",
    "EffectiveAuthorityEntry",
    "MaterialCapabilityClass",
    "PathHop",
    "classify_material_capability",
    "compute_blast_radius",
    "compute_direct_capability_paths",
    "compute_effective_authority",
    "compute_transitive_capability_paths",
    "describe_blast_radius",
    "effective_authority_digest",
    "worst_class",
]
