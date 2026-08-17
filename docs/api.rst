Python API reference
====================

Run lifecycle
-------------

.. automodule:: health_deid.api
   :members: PrecheckError, PrecheckResult, RunHandle, create_run, launch_ui, open_run, precheck, run

Configuration
-------------

.. automodule:: health_deid.models.config
   :members: PipelineConfig, RunConfig, InputConfig, DetectionConfig, AwsComprehendDetectorConfig, BedrockLlmDetectorConfig, RulesConfig, ValidationConfig, ReviewConfig, ExecutionConfig, load_config

Replacement policy
------------------

.. automodule:: health_deid.models.policy
   :members: TransformationPolicy, CategoryPolicy, FakerSurrogate, CustomListSurrogate, DateShiftSurrogate, ConsistencyScope

Backend interfaces
------------------

.. automodule:: health_deid.backends.contracts
   :members: PhiDetector, PhiValidator
