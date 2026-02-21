#!/usr/bin/env node
import { main as pki_main } from "../lib/ca/crypto_create_CA";

pki_main(process.argv.splice(2));
