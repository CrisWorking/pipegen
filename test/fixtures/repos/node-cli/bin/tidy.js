#!/usr/bin/env node
import { program } from 'commander';
program.name('tidy').action(() => console.log('tidy'));
program.parse();
