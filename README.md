# Scapy HTTP/2 Example

## Installation

Create virtual environment

```shell
python -m venv .venv
```

Install dependencies (scapy)

```shell
pip install -r requirements.txt
```

## Usage

```shell
python src/main.py
```

## See Also

- [Scapy HTTP/2 Tutorial](https://github.com/secdev/scapy/blob/master/doc/notebooks/HTTP_2_Tuto.ipynb)
  the Scapy Docs defer to - does not work out of the box but is a fantastic
  starting point
- [H2Tinker](https://github.com/kspar/h2tinker) - has some more correct and
  stronger usage
- [RFC 7540 - HTTP/2](https://datatracker.ietf.org/doc/html/rfc7540) - as the
  authoritative source for HTTP/2, the HTTP/2 specification can help debug why
  things aren't working
