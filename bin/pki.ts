#!/usr/bin/env node
import { pki_main } from "node-opcua-pki";

pki_main(process.argv.splice(2));
