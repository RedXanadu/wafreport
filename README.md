# wafreport
ModSecurity summary report utility

Inspired by `modsec-positive-stats.rb` by [Christian Folini](https://github.com/dune73) (see: https://github.com/Apache-Labor/labor). Designed for systems without access
to a Ruby environment.

This utility prints a table of statistics based on ModSecurity with OWASP CRS inbound and outbound anomaly score totals. For example:

```
Inbound (Requests)
------------------               # of req. | % of req. | Cumulative | Outstanding
          Total number of requests | 10000 | 100.0000% | 100.0000%  |   0.0000%

Empty or invalid inbound score     |     0 |   0.0000% |   0.0000%  | 100.0000%
Requests with inbound score of   0 |  5583 |  55.8300% |  55.8300%  |  44.1700%
Requests with inbound score of   5 |    30 |   0.3000% |  56.1300%  |  43.8700%
Requests with inbound score of   8 |     1 |   0.0100% |  56.1400%  |  43.8600%
Requests with inbound score of  10 |  3194 |  31.9400% |  88.0800%  |  11.9200%
⋮
Requests with inbound score of 231 |     6 |   0.0600% | 100.0000%  |   0.0000%

Mean: 12.53    Median: 0.00



Outbound (Responses)
--------------------            # of res. | % of res. | Cumulative | Outstanding
        Total number of responses | 10000 | 100.0000% | 100.0000%  |   0.0000%

Empty or invalid outbound score   |     0 |   0.0000% |   0.0000%  | 100.0000%
Responses with inbound score of 0 | 10000 | 100.0000% | 100.0000%  |   0.0000%

Mean: 0.00    Median: 0.00
```

## Compiling

Use `make` to take care of compilation:

```bash
make
```

## Usage

The utility expects to receive data on `stdin`, one request / log entry per line, in the form

``INBOUND_ANOMALY_SCORE`` ``OUTBOUND_ANOMALY_SCORE``

e.g.

``5 0``

Intended to be used with grep, piping in anomaly scores like so:

  ```bash
  grep -E -o "[0-9-]+ [0-9-]+$" my_waf.log | ./wafreport
  ```
