from typing import TypeVar, Callable, Union, Coroutine, AsyncGenerator, Generator, AsyncIterator

TReturnType = TypeVar('TReturnType')
TOptions = TypeVar('TOptions')
THandler = TypeVar('THandler')
TService = TypeVar('TService')
TImplementation = TypeVar('TImplementation')

DependencyCallable = Callable[
    ...,
    Union[
        TReturnType,
        Coroutine[None, None, TReturnType],
        AsyncGenerator[TReturnType, None],
        Generator[TReturnType, None, None],
        AsyncIterator[TReturnType],
    ],
]
