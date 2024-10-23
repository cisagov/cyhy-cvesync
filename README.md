# cyhy-cvesync #

[![GitHub Build Status](https://github.com/cisagov/cyhy-cvesync/workflows/build/badge.svg)](https://github.com/cisagov/cyhy-cvesync/actions)
[![CodeQL](https://github.com/cisagov/cyhy-cvesync/workflows/CodeQL/badge.svg)](https://github.com/cisagov/cyhy-cvesync/actions/workflows/codeql-analysis.yml)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/cyhy-cvesync/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/cyhy-cvesync?branch=develop)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/cyhy-cvesync/develop/badge.svg)](https://snyk.io/test/github/cisagov/cyhy-cvesync)

`cyhy-cvesync` is Python library that can retrieve JSON files containing Common
Vulnerabilities and Exposures (CVE) data (such as those from the [National
Vulnerability Database (NVD)](https://nvd.nist.gov/)) and import the data into a
MongoDB collection.

## Pre-requisites ##

- [Python 3.12](https://www.python.org/downloads/) or newer
- A running [MongoDB](https://www.mongodb.com/) instance that you have access to

## Starting a Local MongoDB Instance for Testing ##

> [!IMPORTANT]
> This requires [Docker](https://www.docker.com/) to be installed in
> order for this to work.

You can start a local MongoDB instance in a container with the following
command:

```console
pytest -vs --mongo-express
```

> [!NOTE]
> The command `pytest -vs --mongo-express` not only starts a local
> MongoDB instance, but also runs all the `cyhy-cvesync` unit tests, which will
> create various collections and documents in the database.

Sample output (trimmed to highlight the important parts):

```console
<snip>
MongoDB is accessible at mongodb://mongoadmin:secret@localhost:32784 with database named "test"
Mongo Express is accessible at http://admin:pass@localhost:8081

Press Enter to stop Mongo Express and MongoDB containers...
```

Based on the example output above, you can access the MongoDB instance at
`mongodb://mongoadmin:secret@localhost:32881` and the Mongo Express web
interface at `http://admin:pass@localhost:8081`.  Note that the MongoDB
containers will remain running until you press "Enter" in that terminal.

## Example Usage ##

Once you have a MongoDB instance running, the sample Python code below
demonstrates how to initialize the CyHy database, fetch CVE data from a source,
and then load the data into to your database.

```python
import asyncio
from cyhy_db import initialize_db
from cyhy_db.models import CVEDoc
from cyhy_cvesync import DEFAULT_CVE_URL_PATTERN
from cyhy_cvesync.cve_sync import process_urls

async def main():
    # Initialize the CyHy database
    await initialize_db("mongodb://mongoadmin:secret@localhost:32881", "test")

    # Count number of CVE documents in DB before sync
    cve_count_before = await CVEDoc.find_all().count()
    print(f"CVE documents in DB before sync: {cve_count_before}")

    # Fetch CVE data from the default source for a single year and sync it to the database
    created_cve_docs_count, updated_cve_docs_count, deleted_cve_docs_count = await process_urls([DEFAULT_CVE_URL_PATTERN.format(year=2024)], cve_data_gzipped=True)

    print(f"Created CVE documents: {created_cve_docs_count}")
    print(f"Updated CVE documents: {updated_cve_docs_count}")
    print(f"Deleted CVE documents: {deleted_cve_docs_count}")

    # Count number of CVE documents in DB after sync
    cve_count_after = await CVEDoc.find_all().count()
    print(f"CVE documents in DB after sync: {cve_count_after}")

asyncio.run(main())
```

Output:

```console
CVE documents in DB before sync: 2
Processing CVE feed ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:16
Deleting outdated CVE docs ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
Created CVE documents: 11644
Updated CVE documents: 0
Deleted CVE documents: 2
CVE documents in DB after sync: 11644
```

### Environment Variables ###

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_INITDB_ROOT_USERNAME` | The MongoDB root username | `mongoadmin` |
| `MONGO_INITDB_ROOT_PASSWORD` | The MongoDB root password | `secret` |
| `DATABASE_NAME` | The name of the database to use for testing | `test` |
| `MONGO_EXPRESS_PORT` | The port to use for the Mongo Express web interface | `8081` |

### Pytest Options ###

| Option | Description | Default |
|--------|-------------|---------|
| `--mongo-express` | Start a local MongoDB instance and Mongo Express web interface | n/a |
| `--mongo-image-tag` | The tag of the MongoDB Docker image to use | `docker.io/mongo:latest` |
| `--runslow` | Run slow tests | n/a |

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
