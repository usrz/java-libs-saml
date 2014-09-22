#!/bin/sh

export SGML_CATALOG_FILES="`dirname $0`/schemas/catalog.xml"

exec xmllint --catalogs --schema http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd "$@"
