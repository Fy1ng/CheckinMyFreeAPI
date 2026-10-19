# Third-party notices

## Metapi

The static permutation/XOR calculation in `utils/acw_challenge.py` is adapted
from Metapi's `src/server/services/platforms/newApiShield.ts`. The offline
fixture `tests/fixtures/anyrouter_acw_challenge.html` is copied from Metapi's
`src/server/services/platforms/__fixtures__/anyrouter-challenge.html`.

Source: https://github.com/cita-777/metapi

Reference revision: `c0d7d7a3231fdfe7cffa78058da66a8fd10741c6`.
The corresponding calculation was also checked against upstream revision
`88634b0d7207039e8d0c0d026c38870cf74bf2bc`.

The Python implementation statically validates a known complete template; it
does not execute the JavaScript or use Metapi's Node.js VM execution path.

MIT License

Copyright (c) 2026 Metapi contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
