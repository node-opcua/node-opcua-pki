const fs = require("node:fs");
const path = require("node:path");

const packageJsonPath = path.join(__dirname, "..", "package.json");
const backupPath = path.join(__dirname, "..", "package.json.bak");

const command = process.argv[2]; // 'clean' or 'restore'

console.log(`Running prepare-publish script with command: ${command}`);

if (command === "clean") {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));

    // Create a backup of the original file
    fs.copyFileSync(packageJsonPath, backupPath);
    console.log("Created backup of package.json.");

    // Remove the sections you don't want to publish
    delete packageJson.devDependencies;
    delete packageJson.scripts;

    // Overwrite the package.json with the cleaned version
    fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
    console.log("Cleaned package.json for publishing.");
} else if (command === "restore") {
    // Restore the original package.json from backup
    fs.renameSync(backupPath, packageJsonPath);
    console.log("Restored original package.json.");
}
