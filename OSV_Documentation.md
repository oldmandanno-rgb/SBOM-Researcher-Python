API (1.0)
Download the OpenAPI specification
Download Here

OSV API
Want a quick example?
Please see the quickstart.

How does the API work?
There are five different types of requests that can be made of the API.

Query vulnerabilities for a particular project at a given commit hash or version.
Batched query vulnerabilities for given package versions and commit hashes.
Return a Vulnerability object for a given OSV ID.
Return a list of probable versions of a specified C/C++ project. (Experimental)
Retrieve records failing import-time quality checks, by record source (Experimental)
Is the API rate limited?
Currently there are no limits on the API.

Are there any response size limits?
The API has a response size limit of 32MiB when using HTTP/1.1. There is no limit when using HTTP/2.

We recommend using HTTP/2 for queries that may result in large responses (e.g. big OSV Linux queries).

Table of contents
API Quickstart
POST /v1/query
POST /v1/querybatch
GET /v1/vulns/{id}
GET /v1experimental/importfindings
POST /v1experimental/ determineversion

Quickstart
Here are a couple of examples that you can run to get an idea of the API. See here for further information.

Return a vulnerability associated with a commit hash
curl -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
    "https://api.osv.dev/v1/query"

Return all vulnerabilities for a given package
curl -d \
          '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
          "https://api.osv.dev/v1/query"


POST /v1/query
Lists vulnerabilities for given package and version. May also be queried by commit hash.

To query multiple packages at once, see further information here.

Table of contents
POST /v1/query
Parameters
Version rules
Queries for Git records
Payload
Request samples
Sample 200 response
Pagination
Parameters
Parameter	Type	Description
commit	string	The commit hash to query for. If specified, version should not be set.
version	string	The version string to query for. A fuzzy match is done against upstream versions. If set, commit must not be used, and package.purl must not include a version.
package	object	The package to query against. When a commit hash is given, this is optional.
page_token	string	If your previous query fetched a large number of results, the response will be paginated. This is an optional field. Please see the pagination section for more information.
Package Objects can be described by package name AND ecosystem OR by the package URL.

Version rules
Use either the top-level version field or a versioned purl (pkg:...@<version>), but not both.
Requests that specify the version in both places return 400 Bad Request.
Examples:

Valid:

{ "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "3.1.4" }
{ "package": { "purl": "pkg:pypi/jinja2@3.1.4" } }
{ "package": { "purl": "pkg:pypi/jinja2" }, "version": "3.1.4" }

Invalid (400 Bad Request):

{ "package": { "purl": "pkg:pypi/jinja2@3.1.4" }, "version": "3.1.4" }

Attribute	Type	Description
name	string	Name of the package. Should match the name used in the package ecosystem (e.g. the npm package name). For C/C++ projects integrated in OSS-Fuzz, this is the name used for the integration. If using name to specify the package, ecosystem must also be used and purl should not be set.
ecosystem	string	The ecosystem for this package. For the complete list of valid ecosystem names, see here. Must be included if identifying the package by name. If specifying by name and ecosystem, purl should not be set.
purl	string	The package URL for this package. If purl is used to specify the package, name and ecosystem should not be set.
Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use ‘PyPI’ instead of ‘pypi’.

Queries for Git records
You can also query for git tags via this API. To do so, set the ecosystem to GIT, enter the full URL of the repository to the name field, and the tag into the version field. See below for an example.

Payload
{
  "commit": "string",
  "version": "string",
  "package": {
    "name": "string",
    "ecosystem": "string",
    "purl": "string"
  },
  "page_token": "string"
}

Request samples
# Commit query
curl -d \
  '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query"

# Package and version query
curl -d \
  '{"package": {"name": "nokogiri", "ecosystem": "RubyGems"}, "version": "1.18.2"}' \
  "https://api.osv.dev/v1/query"

# Git query by tag
curl -d \
  '{"package": {"name": "https://github.com/curl/curl.git", "ecosystem": "GIT"}, "version": "8.5.0"}' \
  "https://api.osv.dev/v1/query"

Sample 200 response
{
  "vulns": [
    {
      "id": "OSV-2020-744",
      "summary": "Heap-double-free in mrb_default_allocf",
      "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801\n\n```\nCrash type: Heap-double-free\nCrash state:\nmrb_default_allocf\nmrb_free\nobj_free\n```\n",
      "modified": "2022-04-13T03:04:39.780694Z",
      "published": "2020-07-04T00:00:01.948828Z",
      "references": [
        {
          "type": "REPORT",
          "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801"
        }
      ],
      "affected": [
        {
          "package": {
            "name": "mruby",
            "ecosystem": "OSS-Fuzz",
            "purl": "pkg:generic/mruby"
          },
          "ranges": [
            {
              "type": "GIT",
              "repo": "https://github.com/mruby/mruby",
              "events": [
                {
                  "introduced": "9cdf439db52b66447b4e37c61179d54fad6c8f33"
                },
                {
                  "fixed": "97319697c8f9f6ff27b32589947e1918e3015503"
                }
              ]
            }
          ],
          "versions": [
            "2.1.2",
            "2.1.2-rc",
            "2.1.2-rc2"
          ],
          "ecosystem_specific": {
            "severity": "HIGH"
          },
          "database_specific": {
            "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/mruby/OSV-2020-744.yaml"
          }
        }
      ],
      "schema_version": "1.4.0"
    }
  ]
}


Pagination
The OSV.dev API uses pagination for queries that return a large number of vulnerabilities. When pagination is used, the next_page_token is given in the response, indicating that there are more results to return. You will need to run additional queries using the page_token to see the remaining results, repeating queries until the next_page_token is no longer included in the response.

For the v1/query endpoint pagination will occur when there more than 1,000 vulnerabilities in the response, or when the query has exceeded 20 seconds. The page size can vary slightly because of threading and may change in the future.

A response indicating pagination will be in this form:

{
  "vulns": [
    ...
  ],
  "next_page_token": "a base64 string here"
}

To get the next page of results, your next request must include page_token:


curl -d \
  '{"package": {...}, "version": ..., "page_token": next_page_token from response}' \
  "https://api.osv.dev/v1/query"


The API has a response size limit of 32MiB when using HTTP/1.1. There is no limit when using HTTP/2. We recommend using HTTP/2 for queries that may result in large responses.

In rare cases, the response might contain only the next_page_token. In those cases, there might be more data that can be retrieved, but were not found within the time limit, please keep querying with the next_page_token until either results are returned, or no more page tokens are returned.

POST /v1/querybatch
Query for multiple packages (by either package and version or git commit hash) at once. Returns vulnerability ids and modified field only. The response ordering will be guaranteed to match the input.

Table of contents
POST /v1/querybatch
Parameters
Version rules
Payload
Request sample
Sample 200 response
Pagination
Parameters
The parameters are the same as those in POST /v1/query, but you can make multiple queries.

Instructions are available for handling pagination for querybatch requests.

Version rules
Each query item must follow the same rules as /v1/query:

Use either version or a versioned purl, not both.
Items with both will return 400 Bad Request.
Payload
{
  "queries": [
    {
      "commit": "string",
      "version": "string",
      "package": {
        "name": "string",
        "ecosystem": "string",
        "purl": "string"
      },
      "page_token": "string",
    }, 
    {
      "commit": "string",
      "version": "string",
      "package": {
        "name": "string",
        "ecosystem": "string",
        "purl": "string"
      },
      "page_token": "string",
    }
  ]
}

Request sample
cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        "purl": "pkg:pypi/mlflow@0.4.0"
      }
    },
    {
      "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
    },
    {
      "package": {
        "ecosystem": "PyPI",
        "name": "jinja2"
      },
      "version": "2.4.1"
    }
  ]
}
EOF

Sample 200 response
{
  "results":
    [
      {
        "vulns":
          [
            {
              "id":"GHSA-vqj2-4v8m-8vrq",
              "modified":"2023-03-14T05:47:39.989396Z"
            },
            {
              "id":"GHSA-wp72-7hj9-5265",
              "modified":"2023-03-24T22:28:29.389429Z"
            },
            {
              "id":"GHSA-xg73-94fp-g449",
              "modified":"2023-03-24T22:54:55.516821Z"
            },
            {
              "id":"PYSEC-2022-28",
              "modified":"2022-03-02T06:39:30.836439Z"
            }
          ]
      },
      {
        "vulns":
          [
            {
              "id":"OSV-2020-484",
              "modified":"2022-04-13T03:04:32.842142Z"
            }
          ]
      },
      {
        "vulns":
          [
            {
              "id":"GHSA-462w-v97r-4m45",
              "modified":"2023-03-10T05:23:41.874079Z"
            },
            {
              "id":"GHSA-8r7q-cvjq-x353",
              "modified":"2023-03-08T05:47:11.461578Z"
            },
            {
              "id":"GHSA-fqh9-2qgg-h84h",
              "modified":"2023-03-09T05:31:42.262435Z"
            },
            {
              "id":"GHSA-g3rq-g295-4j3m",
              "modified":"2023-03-12T05:29:26.243227Z"
            },
            {
              "id":"GHSA-hj2j-77xm-mc5v",
              "modified":"2023-03-12T05:32:53.675797Z"
            },
            {
              "id":"PYSEC-2014-8",
              "modified":"2021-07-05T00:01:22.043149Z"
            },
            {
              "id":"PYSEC-2014-82",
              "modified":"2021-08-27T03:22:05.027573Z"
            },
            {
              "id":"PYSEC-2019-217",
              "modified":"2021-11-22T04:57:52.862665Z"
            },
            {
              "id":"PYSEC-2019-220",
              "modified":"2021-11-22T04:57:52.929678Z"
            },
            {
              "id":"PYSEC-2021-66",
              "modified":"2021-03-22T16:34:00Z"
            }
          ]
        }
    ]
}

Pagination
Pagination for the querybatch API works similarly to the v1/query endpoint. However, a querybatch request may return results with a next_page_token for only a few of the total queries. In this situation, you will need to run additional requests for those specific queries to see the remaining results.

For the v1/querybatch endpoint pagination will occur when at least one of the following conditions are met:

An individual query within the queryset returns more than 1,000 vulnerabilities
The entire queryset returns more than 3,000 vulnerabilities total
These numbers can vary slightly because of threading and the page size may change in the future.

A queryset response with paginated results will be in this form:

{
  "results": [
    {
      "vulns": [
        ...
      ],
      "next_page_token": "token for query 1"
    },
    {
      "vulns": [
        ...
      ],
      "next_page_token": "token for query 2"
    },
    {
      "vulns": [
        ...
      ],
    },
    ...
  ]
}

Notice that each result has a distinct next_page_token and that the third result does not include a next_page_token. This indicates that all of the vulnerabilities for the third query have been returned.

To get the next page of results, your next request should specify page_token only for the queries that returned next_page_token.

cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        ...
      },
      "version": ..., 
      "page_token": next_page_token from query 1,
    },
    {
      "package": {
        ...
      },
      "version": ...,
      "page_token": next_page_token from query 2,
    },
  ]
}
EOF

GET /v1/vulns/{id}
Returns vulnerability information for a given vulnerability id.

Table of contents
GET /v1/vulns/{id}
Parameters
Request sample
Sample 200 response
Parameters
The only parameter you need for this API call is the vulnerability id, in order to construct the URL.

https://api.osv.dev/v1/vulns/{id}

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use ‘GHSA’ instead of ‘ghsa’.

Request sample
curl "https://api.osv.dev/v1/vulns/OSV-2020-111"

Sample 200 response
{
  "id": "OSV-2020-111",
  "summary": "Heap-use-after-free in int std::__1::__cxx_atomic_fetch_sub<int>",
  "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604\n\n```\nCrash type: Heap-use-after-free WRITE 4\nCrash state:\nint std::__1::__cxx_atomic_fetch_sub<int>\nstd::__1::__atomic_base<int, true>::operator--\nObject::free\n```\n",
  "modified": "2022-04-13T03:04:37.331327Z",
  "published": "2020-06-24T01:51:14.570467Z",
  "references": [
    {
      "type": "REPORT",
      "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604"
    }
  ],
  "affected": [
    {
      "package": {
        "name": "poppler",
        "ecosystem": "OSS-Fuzz",
        "purl": "pkg:generic/poppler"
      },
      "ranges": [
        {
          "type": "GIT",
          "repo": "https://anongit.freedesktop.org/git/poppler/poppler.git",
          "events": [
            {
              "introduced": "e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499"
            },
            {
              "fixed": "155f73bdd261622323491df4aebb840cde8bfee1"
            }
          ]
        }
      ],
      "ecosystem_specific": {
        "severity": "HIGH"
      },
      "database_specific": {
        "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/poppler/OSV-2020-111.yaml"
      }
    }
  ],
  "schema_version": "1.4.0"
}

GET /v1experimental/importfindings/{source}
Experimental
Given a specific OSV.dev source, report any records that are failing import-time quality checks.

Table of contents
GET /v1experimental/importfindings/{source}
Experimental endpoint
Purpose
Parameters
Request sample
Example 200 response
Experimental endpoint
This API endpoint is still considered experimental. It is targeted to operators of home databases that OSV.dev imports from. We would value any and all feedback. If you give this a try, please consider opening an issue and letting us know about any pain points or highlights.

Purpose
The purpose of this endpoint is give OSV record providers (home database operators) a machine-readable way to reason about records they have published that do not meet OSV.dev’s quality bar (and therefore have not been imported).

Parameters
The only parameter you need for this API call is the source, in order to construct the URL.

https://api.osv.dev/v1experimental/importfindings/{source}

The source value is the same as the name value in source.yaml

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use ‘ghsa’ instead of ‘GHSA’.

Request sample
curl "https://api.osv.dev/v1experimental/importfindings/example"

Example 200 response
{"invalid_records":[{"bug_id":"EX-1234","source":"example","findings":["IMPORT_FINDING_TYPE_INVALID_JSON"],"first_seen":"2024-12-19T15:18:00.945105Z","last_attempt":"2024-12-19T15:18:00.945105Z"}]}

POST /v1experimental/determineversion
Experimental
Given the source code hashes of C/C++ libraries, this endpoint attempts to find the closest upstream library and version.

Table of contents
POST /v1experimental/determineversion
Experimental endpoint
Purpose
Available libraries
Try the API with our tool
Steps to use the indexer-api-caller
Interpreting the API response
Use the API manually
Parameters
Manual API calls
Payload
Response
Sample 200 response
Experimental endpoint
This API endpoint is still considered experimental. We would value any and all feedback. If you give this a try, please consider opening an issue and letting us know about any pain points or highlights.

Purpose
The purpose of the endpoint is to help determine the package and version of a given C/C++ library. This is not as straightforward of a process compared to other ecosystems, because there is not a centralized package manager for C/C++. This API endpoint helps bridge that gap. Once you have the likely version, you can use POST v1/query or POST v1/querybatch to search for vulnerabilities.

Available libraries
The list of libraries that can currently be identified are the C/C++ projects integrated into the OSS-Fuzz project. This means that not all C/C++ packages are represented in our database. We’re actively working on increasing this coverage, and combining this effort with building a comprehensive database of vulnerabilities for C/C++.

To confirm if the package you are interested in can be versioned by the determineversion API, please check the following resources for your package:

All available package information can be found here.
You can look up your specific package using a url in the form https://storage.googleapis.com/osv-indexer-configs/generated/{your-package}.yaml For example, if you are interested in the library protobuf, you can find information for it at https://storage.googleapis.com/osv-indexer-configs/generated/protobuf.yaml.
You can use gsutil to copy everything: gcloud storage cp --recursive gs://osv-indexer-configs/ .
Try the API with our tool
We recommend trying the API endpoint with our indexer-api-caller tool. The index-api-caller will gather all of the data (file paths and MD5 hashes) that you need, make the API call for you, and return the response.

Steps to use the indexer-api-caller
Have a local copy of this repository.
Navigate to /osv.dev/tools/indexer-api-caller
Run the tool with the following commands:
For a single library: go run . -lib path/to/library
For a directory with multiple libraries as top level subdirectories: go run . -dir /path/to/libs/dir
Evaluate the response
Interpreting the API response
The API will return a number of possible versions for your package, ranked by how well the version matched your local copy. Depending on the needs of your project and how close your matches were, you may want to search for vulnerabilities for a few of the most likely versions. If you are searching for multiple versions, the /v1/querybatch endpoint is a good choice.

Use the API manually
If you want to use the API manually, or build your own tool to use the endpoint, the following information will help you do so.

Parameters
Parameter	Type	Description
name	string	Optional name to help hint the package search.
file_hashes	array	An array of MD5 hashes of each relevant file in the library to identify.
file_hashes.hash	string	the MD5 hash bytes encoded in base64.
file_hashes.file_path	string	the path to the file that’s hashed, relative to the root directory of the library
Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use ‘stdlib’ instead of ‘Stdlib’.

Manual API calls
After locating the library directory, walk through the directory, saving the MD5 hash of every file with the following extensions:

.c
.cc
.h
.hh
.cpp
.hpp
And pass each file hash to the endpoint following the format below:

Payload
{
  "name": "string",
  "file_hashes": [
    {
      "hash": "base64 string of MD5 hash bytes",
      "file_path": "string",
    }
  ]
}

Response
Returns an array of potential library matches, sorted by how close the match is.

{
  "matches": [
    {
      "score": 0.5, // float between 0.0 - 1.0
      "repo_info": {
        "type": "string", // e.g. GIT
        "address": "string", // Repo Address
        "tag": "string", // Git tag
        "version": "string" // Library version
      },
      "minimum_file_matches": "string", // Number of exact hash matches
      "estimated_diff_files": "string" // Estimated number of different files
    },
  ]
}

Sample 200 response
{
  "matches": [
    {
      "score": 1,
      "repo_info": {
        "type": "GIT",
        "address": "https://github.com/protocolbuffers/protobuf.git",
        "tag": "v4.22.2",
        "version": "4.22.2"
      },
      "minimum_file_matches": "617"
    },
    {
      "score": 0.97730956239870337,
      "repo_info": {
        "type": "GIT",
        "address": "https://github.com/protocolbuffers/protobuf.git",
        "tag": "v4.22.1",
        "version": "4.22.1"
      },
      "minimum_file_matches": "575",
      "estimated_diff_files": "14"
    }
  ]
}


Data sources
Table of contents
Current data sources
Converted data
Covered Ecosystems
Data Quality
Data dumps
Full database download
Per-ecosystem downloads
Downloading recent changes
Ecosystem naming
Contributing Data
Current data sources
This is an ongoing project. We encourage open source ecosystems to adopt the Open Source Vulnerability format to enable open source users to easily aggregate and consume vulnerabilities across all ecosystems. See our blog post for more details.

The following ecosystems have vulnerabilities encoded in this format:

GitHub Advisory Database (CC-BY 4.0)
PyPI Advisory Database (CC-BY 4.0)
Go Vulnerability Database (CC-BY 4.0)
Rust Advisory Database (CC0 1.0)
Drupal Advisory Database (MIT)
Global Security Database (CC0 1.0)
OSS-Fuzz (CC-BY 4.0)
Rocky Linux (BSD)
AlmaLinux (MIT)
Haskell Security Advisories (CC0 1.0)
RConsortium Advisory Database (Apache 2.0)
OpenSSF Malicious Packages (Apache 2.0)
Python Software Foundation Database (CC-BY 4.0)
Bitnami Vulnerability Database (Apache 2.0)
Haskell Security Advisory DB (CC0 1.0)
Ubuntu (CC-BY-SA 4.0)
opam (OCaml package manager) (CC0 1.0)
Erlang Ecosystem Foundation CNA (CC-BY 4.0)
Converted data
Additionally, the OSV.dev team maintains a conversion pipeline for:

Debian Security Advisories, using the conversion tools here.
Alpine SecDB, using the conversion tools here,
NVD CVEs for open source software using the conversion tools here
Covered Ecosystems
Between the data served in OSV and the data converted to OSV the following ecosystems are covered.

AlmaLinux
Alpine
Android
Bitnami
crates.io
Curl
Debian GNU/Linux
Git (including C/C++)
GitHub Actions
Go
Haskell
Hex
Julia
Linux kernel
Maven
npm
NuGet
opam (OCaml package manager)
OSS-Fuzz
Packagist
Pub
PyPI
Python
R (CRAN and Bioconductor)
Rocky Linux
Root
RubyGems
SwiftURL
Ubuntu OS
Data Quality
The quality of the data in OSV.dev is very important to us. The minimum quality bar for OSV records acceptable for import is documented here

Data dumps
For convenience, these sources are aggregated and continuously exported to a GCS bucket maintained by OSV: gs://osv-vulnerabilities

Full database download
This bucket contains a zip file with all vulnerabilities across all ecosystems (including withdrawn records) at gs://osv-vulnerabilities/all.zip. This is the easiest way to download the entire OSV database.

Per-ecosystem downloads
Individual vulnerability records can be found at gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json. A zip containing all vulnerabilities for each ecosystem is available at gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip. Vulnerabilities without an ecosystem (typically withdrawn ones) are exported to the gs://osv-vulnerabilities/[EMPTY]/ directory.

E.g. for PyPI vulnerabilities:

# Or download over HTTP via https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip
gcloud storage cp gs://osv-vulnerabilities/PyPI/all.zip .

Downloading recent changes
To efficiently download only new or updated records, you can use the modified_id.csv files. These files list vulnerabilities by their last modified time.

Two types of CSV files are provided:

A top-level file: Located at gs://osv-vulnerabilities/modified_id.csv, this file contains a list of all modified vulnerabilities across all ecosystems.
Per-ecosystem files: Each ecosystem directory (e.g., gs://osv-vulnerabilities/PyPI/) contains its own modified_id.csv file, listing only the vulnerabilities for that specific ecosystem.
Format and Usage

The format of the top-level CSV is <iso modified date>,<ecosystem_dir>/<id>. The per-ecosystem files omit the <ecosystem_dir>/ prefix.

For example (from the top-level file):

2024-08-15T00:05:00Z,PyPI/PYSEC-2021-123
2024-08-15T00:01:00Z,Go/GO-2022-0123
2024-08-14T12:00:00Z,npm/1234

The CSV files are sorted in reverse chronological order. This allows you to stream the file and stop processing when you encounter a timestamp that you have already seen, avoiding the need to parse the entire file.

Ecosystem naming
Some ecosystems contain a : separator in the name (e.g. Alpine:v3.17). For these ecosystems, the data dump will always contain an ecosystem directory without the :.* suffix (e.g. Alpine). This will contain all the advisories of the ecosystem with the same prefix (e.g. All Alpine:.*).

A list of all current ecosystems is available at gs://osv-vulnerabilities/ecosystems.txt

Note: OSV.dev has stopped exporting entries for ecosystems with prefixes (e.g. All Alpine:.*). Please refer only to the main ecosystem, the one without the :.* suffix, for all vulnerabilities of that ecosystem.

Contributing Data
If you work with a project such as a Linux distribution and would like to contribute your security advisories, please follow the steps outlined in the New Data Source page.

Data can be supplied either through a public Git repository, to REST API endpoints, or through a public GCS bucket.

Table of contents
New Data Source
