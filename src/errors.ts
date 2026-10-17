export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    message?: string,
  ) {
    super(message ?? title);
    this.name = new.target.name;
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'The requested resource does not exist') {
    super(404, 'Not Found', message);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'The resource already exists') {
    super(409, 'Conflict', message);
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super(400, 'Bad Request', message);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'A valid API token is required') {
    super(401, 'Unauthorized', message);
  }
}

function pgCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : undefined;
}

export const isUniqueViolation = (err: unknown): boolean => pgCode(err) === '23505';
export const isForeignKeyViolation = (err: unknown): boolean => pgCode(err) === '23503';
