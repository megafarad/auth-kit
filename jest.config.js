import {createDefaultPreset} from "ts-jest";

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
export default {
    preset: "ts-jest",
    testEnvironment: "node",
    setupFiles: ["dotenv/config"],
    moduleFileExtensions: ["ts", "js", "d.ts"],
    transform: {
        ...tsJestTransformCfg,
    },
};