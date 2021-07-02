#!/usr/bin/env ts-node
import { test }  from 'tstest'
import { bundleTsFile } from './bundle-ts-file'

test('bundleTsFile()', async t => {
  const TS_FILE = require.resolve('./../../tests/fixtures/simple-class.ts')
  const EXPECTED_JS =  '(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module \'"+i+"\'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){\n"use strict";\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, "__esModule", { value: true });\nexports.Test = void 0;\nfunction decorator(...args) { void args; }\nlet Test = class Test {\n};\nTest = __decorate([\n    decorator\n], Test);\nexports.Test = Test;\n\n},{}]},{},[1]);\n'

  const output = await bundleTsFile(TS_FILE)

  t.equal(output, EXPECTED_JS, 'should bundle TS to JS correct')
})
