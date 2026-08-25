import test from 'node:test'; import assert from 'node:assert/strict'; import { validateEnvelope } from '../src/validate.js';
test('accepts a minimal test result',()=>assert.equal(validateEnvelope({status:'passed',passed_count:1499,failed_tests:[],provenance:{source:'fixture'}}).ok,true));
test('requires an escalation reason before raw output',()=>assert.deepEqual(validateEnvelope({status:'failed',provenance:{source:'fixture'},raw_output:'noise'}).errors,['raw output requires escalation reason']));
