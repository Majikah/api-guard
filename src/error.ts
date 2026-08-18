// src/error.ts
// ---------------------------------------------------------------------------
// Errors — thrown only for programmer/config mistakes, never for a
// legitimate "this request didn't verify" outcome (that's VerifyResult).
// ---------------------------------------------------------------------------

export class APIGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "APIGuardError";
  }
}


// Freeze static methods 
Object.freeze(APIGuardError);

// Freeze instance methods
Object.freeze(APIGuardError.prototype);