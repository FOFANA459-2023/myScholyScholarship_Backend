from collections import OrderedDict

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class ScholarshipPagination(PageNumberPagination):
    """Page-number pagination with a client-adjustable, hard-capped page size.

    The response includes ``page``/``total_pages`` so the UI can render a pager
    without a second round trip, and omits the absolute next/previous URLs that
    DRF builds by default (the client composes its own query strings).
    """

    page_size = 24
    page_size_query_param = "page_size"
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response(
            OrderedDict(
                [
                    ("count", self.page.paginator.count),
                    ("page", self.page.number),
                    ("page_size", self.get_page_size(self.request)),
                    ("total_pages", self.page.paginator.num_pages),
                    ("has_next", self.page.has_next()),
                    ("has_previous", self.page.has_previous()),
                    ("results", data),
                ]
            )
        )


class DefaultPagination(ScholarshipPagination):
    page_size = 50
