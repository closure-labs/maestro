# SPDX-License-Identifier: Apache-2.0
{publicCacheWorker}: ''
  export PYTHONDONTWRITEBYTECODE=1
  export MAESTRO_DECISION_CORE=${../../authority/_source/decisions}
  export MAESTRO_NATIVE_PREPARE_SOURCE=${../_source/native-prepare.py}
  export MAESTRO_NATIVE_PREPARE_POLICY=${../../authority/_source/decision-policy.json}
  export MAESTRO_SECURITY_NATIVE_CHECK_SOURCE=${../_source/security-native-check.py}
  export MAESTRO_SECURITY_VERDICT_SOURCE=${../_source/security-verdict.py}
  export MAESTRO_NATIVE_SECURITY_POLICY=${../_source/security-policy.json}
  export MAESTRO_NATIVE_RISK_SOURCE=${../_source/native-risk.py}
  export MAESTRO_NATIVE_STAGE_SOURCE=${../_source/native-stage.py}
  export MAESTRO_NATIVE_CONSUMER_SOURCE=${../../../release/consumer/_source/consumer-probe.py}
  export PUBLICATION_DESTINATIONS_SOURCE=${../../authority/_source/decisions}/destinations.py
  export PUBLICATION_CURL_WORKER_SOURCE=${publicCacheWorker}
  export MAESTRO_DISTRIBUTION_CACHE_SOURCE=${../../graph/_source/distribution-cache.py}
  export MAESTRO_NATIVE_PUBLICATION_SOURCE=${../_source/native-publication.py}
  export MAESTRO_NATIVE_REFRESH_SOURCE=${../_source/native-refresh.py}
  export MAESTRO_NATIVE_HEALTH_SOURCE=${../_source/native-health.py}
''
