#pragma once
#include <Driver.h>

auto RegisterProcessOb()->NTSTATUS;
auto RegisterThreadOb()->NTSTATUS;
auto RegObCall()->NTSTATUS;
auto UnRegObCall()->NTSTATUS;