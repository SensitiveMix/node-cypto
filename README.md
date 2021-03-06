```bash
                      __                                         __        
   ____   ____   ____/ /  ___          _____   __  __    ____   / /_  ____ 
  / __ \ / __ \ / __  /  / _ \ ______ / ___/  / / / /   / __ \ / __/ / __ \
 / / / // /_/ // /_/ /  /  __//_____// /__   / /_/ /   / /_/ // /_  / /_/ /
/_/ /_/ \____/ \__,_/   \___/        \___/   \__, /   / .___/ \__/  \____/ 
                                            /____/   /_/                   
```
[![Build Status](https://travis-ci.org/SensitiveMix/node-cypto.svg?branch=master)](https://travis-ci.org/SensitiveMix/node-cypto)
[![codecov](https://codecov.io/gh/SensitiveMix/node-cypto/branch/master/graph/badge.svg)](https://codecov.io/gh/SensitiveMix/node-cypto)



A module for taking advantage of the built-in node signature module in node v0.8 and should contain host private and public ssh key.

## Installation

[![Greenkeeper badge](https://badges.greenkeeper.io/SensitiveMix/node-cypto.svg)](https://greenkeeper.io/)
```bash
yarn install https://github.com/SensitiveMix/node-cypto
```


## Usage
Initialize Request Handler for Http Signature

```bash
const Crpto = require('phoenix-crpto').client
let cypto = new Crpto('privateKeys','host','port')
cypto
  .then((result)=>{
  console.log(`success return: ${result}`)
  })
  .catch(e=>{
  console.error(`fail return: ${e}`)
  })
```

## Test
```bash
yarn test
```



## License 

MIT License

Copyright (c) 2016 Jack Sun

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


