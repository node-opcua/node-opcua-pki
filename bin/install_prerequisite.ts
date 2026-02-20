#!/usr/bin/env node
import { install_prerequisite } from "node-opcua-pki";

install_prerequisite().catch((err: Error) => {
    console.log("err = ", err.message);
});
