from typing import overload, Callable

from pydentity.authorization import AuthorizationPolicy, AuthorizationPolicyBuilder

from fastapi_pydentity.authorization.options import AUTHORIZATION_OPTIONS


class AuthorizationBuilder:
    """Used to configure authorization."""

    __slots__ = ()

    def __init__(self, default_policy: AuthorizationPolicy | None = None):
        if default_policy:
            AUTHORIZATION_OPTIONS.default_policy = default_policy

    @overload
    def add_policy(self, name: str, policy: AuthorizationPolicy) -> "AuthorizationBuilder":
        """
        Adds a ``AuthorizationPolicy``.

        :param name: The name of this policy.
        :param policy: The ``AuthorizationPolicy``.
        :return:
        """

    @overload
    def add_policy(
            self,
            name: str,
            configure_policy: Callable[[AuthorizationPolicyBuilder], None]
    ) -> "AuthorizationBuilder":
        """
        Add a policy that is built from a delegate with the provided name.

        :param name: The name of the policy.
        :param configure_policy: The delegate that will be used to build the policy.
        :return:
        """

    def add_policy(
            self,
            name: str,
            policy_or_builder: AuthorizationPolicy | Callable[[AuthorizationPolicyBuilder], None]
    ) -> "AuthorizationBuilder":
        AUTHORIZATION_OPTIONS.add_policy(name, policy_or_builder)
        return self

    def __iadd__(self, policy: AuthorizationPolicy):
        """
        Adds a ``AuthorizationPolicy``.

        :param policy: The ``AuthorizationPolicy``.
        :return:
        """
        return self.add_policy(policy.name, policy)
