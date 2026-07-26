"""Profile collections with peer fallback for cold-start entities."""

from dataclasses import dataclass

from behavioral_security.core.models.profile import EntityProfile


@dataclass(frozen=True, slots=True)
class ProfileStore:
    """Entity profiles and progressively broader peer baselines."""

    entities: dict[str, EntityProfile]
    departments: dict[str, EntityProfile]
    entity_types: dict[str, EntityProfile]
    organization: EntityProfile
    known_source_ips: dict[str, frozenset[str]]

    def resolve(
        self,
        entity_id: str,
        department: str | None,
        entity_type: str,
    ) -> EntityProfile:
        """Resolve an entity baseline, falling back through cold-start peers."""

        if entity_id in self.entities:
            return self.entities[entity_id]
        if department and department in self.departments:
            return self.departments[department]
        return self.entity_types.get(entity_type, self.organization)
