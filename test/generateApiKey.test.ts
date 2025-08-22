import {generateApiKey} from "../src";

describe('generateApiKey', () => {
    it('should generate an api key', () => {
        const apiKey = generateApiKey();
        console.log(apiKey);
        expect(apiKey).toBeDefined();
    });
});