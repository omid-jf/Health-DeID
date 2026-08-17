Configuration
=============

Configuration is a version-1 YAML document validated by Pydantic. The UI rule
builder and setup wizard produce the same model used by the CLI and Python API.
The complete validated configuration, including one PHI policy snapshot, is
stored with the run.

Detection
---------

Comprehend Medical and Claude Sonnet 4.6 can be enabled separately or together.
Local exact-text and regular-expression rules may be added in the browser or
loaded from YAML. The supported Sonnet model is fixed to
``us.anthropic.claude-sonnet-4-6``.

Detection and validation each expose ``execution.workers`` from 1 through 8;
the default is 2. AWS transport retries use botocore standard mode.

Cost
----

``health-deid check CONFIG`` and the UI's ``Check setup`` action calculate a
precheck estimate without making paid model calls. Comprehend estimates use
the actual UTF-8 chunk plan and billing units. Bedrock estimates include the
request prompt, schema, serialized content, and configured token prices.

The estimate appears only before processing. Once a run exists, reports and UI
usage cards calculate cost from recorded request usage. A missing price leaves
that backend unpriced instead of treating it as free.

Validation and review
---------------------

Automated validation uses the fixed
``openai.gpt-oss-safeguard-120b`` Bedrock model. Explicitly truncated responses
advance through fixed output-token budgets; no general application retry
framework is used. The validator receives source and draft text only; structured
fields are transformed and reviewed locally.

Review can cover effective validation findings or every record. Review-all is
also available without automated validation.

.. code-block:: yaml

   validation:
     enabled: true
     region_name: us-east-1
     input_cost_per_million_tokens: 0.15
     output_cost_per_million_tokens: 0.60
     execution:
       workers: 2
   review:
     enabled: true
     review_scope: effective_validation_failures

PHI handling
------------

Every PHI category selects one action: retain, redact, generalize, or
surrogate. Non-date surrogates use either ``faker`` or ``custom_list`` and one
of three consistency modes:

``entity``
   Equal original values receive the same replacement within one entity.

``record``
   Equal original values receive the same replacement within one record.

``occurrence``
   Every occurrence receives its own replacement.

Different original values receive distinct replacements within the relevant
container. A custom list that is too small fails with an actionable message.

Dates use ``date_shift`` with one whole-week shift per entity. Dates may instead
be generalized to the year, and ages may be generalized to ``90+``. The same
policy applies to source text and configured structured PHI fields.
