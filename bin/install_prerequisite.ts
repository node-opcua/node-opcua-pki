#!/usr/bin/env node
import { install_prerequisite } from "../lib/toolbox/with_openssl/install_prerequisite";

install_prerequisite().catch((err: Error) => {
    console.log("err = ", err.message);
});
