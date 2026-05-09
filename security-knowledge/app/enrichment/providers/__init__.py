"""Provider package — importing this module triggers @register side-effects.

The provider registry in ``app.enrichment.registry`` is populated lazily by
``@register`` decorators that only fire when each provider module is imported.
Importing them all here ensures ``EnrichmentService`` sees every shipped
provider at startup. Providers that lack credentials self-disable inside
``enrich()`` rather than failing to register, so listing them all here is safe.
"""

from . import (  # noqa: F401  (import-for-side-effects)
    abuseipdb,
    bgp_he,
    crowdstrike,
    greynoise,
    ipinfo,
    misp,
    mitre_attack,
    nvd,
    opencti,
    otx,
<<<<<<< HEAD
    recordedfuture,
=======
>>>>>>> 06b0054cfce62f7f038d3eed0a7ce1c535c54010
    shodan,
    urlscan,
    virustotal,
)
