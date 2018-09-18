#!/usr/bin/env node
"use strict";
var install_prerequisite = require("../dist/lib/misc/install_prerequisite").install_prerequisite;
install_prerequisite(function(err){
    if (err) {
        console.log("err = ",err.message);
    }
});
