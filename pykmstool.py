import click
from click import ClickException
from cryptography import x509
from google.api_core.client_options import ClientOptions
from google.api_core.exceptions import PermissionDenied
from google.cloud import kms
from google.cloud.kms_v1 import CryptoKeyVersion, ProtectionLevel
from google.cloud.location.locations_pb2 import ListLocationsRequest
from google.cloud.resourcemanager import ProjectsClient

from kms_funcs import kms_sign_csr, kms_verify_csr, kms_get_public_key


@click.group()
def cli():
    pass


def list_project_locations(client: kms.KeyManagementServiceClient, project_id: str):
    next_page_token = None

    while True:
        res = client.list_locations(ListLocationsRequest(
            name=f'projects/{project_id}',
            page_size=3,
            page_token=next_page_token
        ))

        for location in res.locations:
            yield location.location_id

        next_page_token = res.next_page_token

        if not next_page_token:
            break


@cli.command(help="List enabled CryptoKeyVersions within a specified location ID and/or project ID.")
@click.option(
    "--location-id",
    help="Location ID to search for KMS keys within.",
    required=True)
@click.option(
    "--project-id",
    help="Project ID to search for KMS keys within. Will check all projects otherwise.",
    required=False)
@click.option(
    "--service-account-file",
    help="Path to the service account key JSON file.",
    required=False)
@click.option(
    "--quota-project-id",
    help="Quota project ID.",
    required=False)
def list_key_versions(location_id, project_id=None, service_account_file=None, quota_project_id=None):
    kms_client = kms.KeyManagementServiceClient(
        client_options=ClientOptions(
            credentials_file=service_account_file,
            quota_project_id=quota_project_id
        )
    )

    check_project_ids = []
    check_location_ids = []

    if project_id:
        check_project_ids.append(project_id)
    else:
        projects_client = ProjectsClient(client_options=ClientOptions(
            credentials_file=service_account_file,
            quota_project_id=quota_project_id
        )).search_projects()

        for project in projects_client:
            check_project_ids.append(project.project_id)

    if location_id:
        check_location_ids.append(location_id)
    else:
        for project_id in check_project_ids:
            for location_id in list_project_locations(kms_client, project_id):
                check_location_ids.append(location_id)

    for project_id in check_project_ids:
        for location_id in check_location_ids:
            location_path = kms_client.common_location_path(project_id, location_id)
            try:
                for key_ring in kms_client.list_key_rings(parent=location_path):
                    try:
                        for crypto_key in kms_client.list_crypto_keys(parent=key_ring.name):
                            try:
                                for crypto_key_version in kms_client.list_crypto_key_versions(parent=crypto_key.name):
                                    if crypto_key_version.state == CryptoKeyVersion.CryptoKeyVersionState.ENABLED:
                                        click.echo(crypto_key_version.name)
                            except PermissionDenied:
                                pass
                    except PermissionDenied:
                        pass
            except PermissionDenied:
                pass


@cli.command(help="Retrieve a PEM encoded public key for given CryptoKeyVersion resource name.")
@click.option(
    "--key-version-name",
    help="Resource name of the CryptoKeyVersion to use.",
    required=True)
@click.option(
    "--service-account-file",
    help="Path to the service account key JSON file.",
    required=False)
@click.option(
    "--quota-project-id",
    help="Quota project ID.",
    required=False)
def get_public_key(key_version_name, service_account_file=None, quota_project_id=None):
    path_parsed = kms.KeyManagementServiceClient.parse_crypto_key_version_path(key_version_name)

    if not path_parsed:
        raise ClickException("Invalid --key-version-name parameter specified. Ensure it follows the "
                             "pattern: projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*")

    client = kms.KeyManagementServiceClient(
        client_options=ClientOptions(
            credentials_file=service_account_file,
            quota_project_id=quota_project_id
        )
    )

    pk_pem = kms_get_public_key(client=client, key_version_name=key_version_name)
    click.echo(pk_pem)


@cli.command(help="Sign a Certificate Signing Request (CSR) using specified CryptoKeyVersion.")
@click.option("--key-version-name", help="Resource name of the CryptoKeyVersion to use.", required=True)
@click.option("--x509-name", help="X.509 RFC4514 name string to embed within the CSR.", required=True)
@click.option("--service-account-file", help="Path to the service account key JSON file.", required=False)
@click.option(
    "--unsafe-dont-require-hsm-protection",
    help="Don\'t require that the key has 'HSM' protection level (may violate compliance).",
    is_flag=True)
@click.option(
    "--unsafe-allow-imported-key",
    help="Allow to use key that was imported from an external source (may violate compliance).",
    is_flag=True)
@click.option(
    "--quota-project-id",
    help="Quota project ID.",
    required=False)
def sign_csr(
        key_version_name,
        x509_name,
        unsafe_dont_require_hsm_protection,
        unsafe_allow_imported_key,
        service_account_file=None,
        quota_project_id=None
):
    path_parsed = kms.KeyManagementServiceClient.parse_crypto_key_version_path(key_version_name)

    if not path_parsed:
        raise ClickException("Invalid --key-version-name parameter specified. Ensure it follows the "
                             "pattern: projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*")

    # unserialize and serialize to verify whether X.509 Name is correct
    try:
        rfc4514_name = x509.Name.from_rfc4514_string(x509_name).rfc4514_string()
    except ValueError:
        raise ClickException(f"Invalid RFC4514 X.509 name: {x509_name}")

    client = kms.KeyManagementServiceClient(
        client_options=ClientOptions(
            credentials_file=service_account_file,
            quota_project_id=quota_project_id
        )
    )

    # we will do some basic compliance checks assuming that the user is expecting
    # that his key is stored on HSM and was locally generated on the HSM
    ckv = client.get_crypto_key_version(name=key_version_name)

    if ckv.protection_level != ProtectionLevel.HSM and not unsafe_dont_require_hsm_protection:
        raise ClickException(f"The specified CryptoKeyVersion has protection level {ckv.protection_level.name}"
                             f" (expected: HSM). Double check if that meets your compliance requirements and if so, "
                             f"repeat this command with '--unsafe-dont-require-hsm-protection' flag.")

    if ckv.import_job and not unsafe_allow_imported_key:
        raise ClickException(f"The specified CryptoKeyVersion was imported through an import job. "
                             f"Double check if that meets your compliance requirements and if so, "
                             f"repeat this command with '--unsafe-allow-imported-key' flag.")

    csr_pem = kms_sign_csr(
        client=client,
        key_version_name=key_version_name,
        rfc4514_name=rfc4514_name
    )
    kms_verify_csr(
        client=client,
        key_version_name=key_version_name,
        csr_pem=csr_pem,
        expected_rfc4514_name=rfc4514_name
    )
    click.echo(csr_pem)


if __name__ == '__main__':
    cli()
