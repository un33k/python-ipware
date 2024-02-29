## 2.0.2

Enhance:
- Added logger name

## 2.0.1

Issue:
- Remove `HTTP_VIA` header support (unreliable IP information) (@yourcelf)

Enhance:
- Include support for python 3.12

## 2.0.0

- Introduced breaking changes to avoid conflicts with the `django-ipware` package.
- Renamed the imported module from `ipware` to `python_ipware` in the `python-ipware` package.
  - Old usage: `from ipware import IpWare`
  - New usage: `from python_ipware import IpWare`

## 1.0.5

- Enhance: Readme updates

## 1.0.0

Features:

- Added `X-CLIENT-IP` header support
- Adds PEP 561 Compatibility (@stumpylog)
- Streamline pyproject.toml & add trusted publishing (@stumpylog)
- Publish version 1.0.0

## 0.9.0

Features:

- Initial Release
