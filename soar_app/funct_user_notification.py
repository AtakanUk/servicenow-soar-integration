"""SOAR app function ``user_notification``.

Function component for an app generated with ``resilient-sdk codegen``.
Inputs: ``incident_id`` and ``notification_profile`` (``atypical_travel``,
``password_spray``, ``malicious_url_click`` or ``mfa_fraud``). The QRadar and
ServiceNow connections are read from the environment of the resilient-circuits
service; SOAR access uses the function's own REST client.
"""

import os

from resilient_circuits import AppFunctionComponent, FunctionResult, app_function
from resilient_lib import IntegrationError, validate_fields

from user_notify.config import ariel_from_env, servicenow_from_env, target_from_env
from user_notify.notify import NotificationError, notify_user
from user_notify.profiles import PROFILES

PACKAGE_NAME = "fn_user_notification"
FN_NAME = "user_notification"


class FunctionComponent(AppFunctionComponent):
    def __init__(self, opts):
        super().__init__(opts, PACKAGE_NAME)

    @app_function(FN_NAME)
    def _app_function(self, fn_inputs):
        validate_fields(["incident_id", "notification_profile"], fn_inputs)
        profile = PROFILES.get(
            getattr(fn_inputs.notification_profile, "name", fn_inputs.notification_profile)
        )
        if profile is None:
            raise IntegrationError(
                f"Unknown notification profile {fn_inputs.notification_profile!r}"
            )

        yield self.status_message(f"Collecting user details for incident {fn_inputs.incident_id}")
        try:
            result = notify_user(
                fn_inputs.incident_id,
                profile,
                soar=self.rest_client(),
                ariel=ariel_from_env(),
                servicenow=servicenow_from_env(),
                target=target_from_env(),
                recipient_property=os.environ.get("SOAR_RECIPIENT_PROPERTY", "qradar_user_email"),
            )
        except NotificationError as exc:
            raise IntegrationError(str(exc)) from exc

        yield FunctionResult(
            {
                "recipient": result.recipient,
                "artifacts_added": result.artifacts_added,
                "servicenow_record": result.record.get("number") or result.record.get("sys_id"),
            }
        )
