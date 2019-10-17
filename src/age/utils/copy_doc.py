def copy_doc(original_function):
    """Decorator to copy docstring from `original_function` to decorated function"""

    def wrapper(func):
        func.__doc__ = original_function.__doc__
        return func

    return wrapper
