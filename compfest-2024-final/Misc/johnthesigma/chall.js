const parse = require('bash-parser');
const { exec } = require('child_process');

const hasBannedChars = (input) => {
    const bannedCharsRegex = /[&`><*?x]/;
    return bannedCharsRegex.test(input);
};

const validateAST = (astNode) => {
    const requiredPrefix = 'whatTHEsigma';
    const hasPrefix = (str, prefix) => str.startsWith(prefix);

    const checkNode = (node) => {
        if (!node || node['type'] !== 'Script') {
            return false;
        }
        for (const command of node['commands']) {
            if (!command || command['type'] !== 'Command') {
                return false;
            }

            let sanitizedText = '';

            if (command['name'] && command['name']['text']) {
                sanitizedText = command['name']['text'].replace(/[^a-zA-Z]/g, '');
            } else if (command['prefix'] && command['prefix'].length > 0) {
                sanitizedText = command['prefix'][0]['text'].replace(/[^a-zA-Z]/g, '');
            }

            if (sanitizedText !== "" && !hasPrefix(sanitizedText, requiredPrefix)) {
                return false;
            }
        }
        return true;
    };
    
    return checkNode(astNode);
};

process.stdout.write(`Input: `);
process.stdin.on('data', (data) => {
    const userInput = data.toString().trim();
    const ast = parse(userInput);

    if (!validateAST(ast)) {
        process.stdout.write('whatTHEsigma\n');
        process.stdin.pause();  // Close the input stream
        return;
    }
    
    if (hasBannedChars(userInput)) {
        process.stdout.write('ban\n');
        process.stdin.pause();  // Close the input stream
        return;
    }
    
    exec(userInput, { shell: '/bin/bash' }, (error, stdout, stderr) => {
        if (error) {
            process.stdout.write(stderr);
            process.stdin.pause();  // Close the input stream
        } else {
            process.stdout.write(stdout);
            process.stdin.pause();  // Close the input stream
        }
    });
});
