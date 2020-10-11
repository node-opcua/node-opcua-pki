

REM replace node-opcua-crypto modules with link to sibling node-opcua-crypto
set N=node-opcua-crypto 
rmdir node_modules\%N% /s /q
mklink /j node_modules\%N% %~dp0..\%N%