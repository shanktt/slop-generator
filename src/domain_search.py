import argparse
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import tqdm
import whois
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from rich.progress import Progress, SpinnerColumn, TextColumn
from tabulate import tabulate
from whois import logger as whois_logger

load_dotenv()

whois_logger.setLevel(logging.CRITICAL)


class Domains(BaseModel):
    domains: list[str] = Field(
        description="A list of potential domains", min_length=20, max_length=20
    )


class DomainSearcher:
    def __init__(self, domains: List[str]):
        self.client = OpenAI()
        self.tlds_to_check = (
            [
                ".com",
                ".co",
                ".ai",
                ".net",
            ]
            if not domains
            else domains
        )

    def get_domains(self, prompt):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            _ = progress.add_task("Generating domains...", total=None)
            response = self.client.responses.parse(
                model="gpt-4o-mini",
                instructions="You are an experment at recommending a list of potential domains given a description of a product or business. The domains you suggest should not contain any subdomains, tlds, etc. Just the plain name itself",
                input=prompt,
                text_format=Domains,
            )
            return response.output_parsed

    def check_domain_availability(self, domain: str) -> Dict[str, any]:
        result = {
            "domain": domain,
            "available": False,
            "error": None,
            "registrar": None,
            "expiration_date": None,
        }

        try:
            try:
                socket.gethostbyname(domain)
                result["available"] = False
            except socket.gaierror:
                pass

            w = whois.whois(domain)

            if w.domain_name is None or (
                isinstance(w.domain_name, list) and len(w.domain_name) == 0
            ):
                result["available"] = True
            else:
                result["available"] = False
                result["registrar"] = w.registrar if hasattr(w, "registrar") else None
                result["expiration_date"] = (
                    str(w.expiration_date) if hasattr(w, "expiration_date") else None
                )

        except whois.parser.PywhoisError:
            result["available"] = True
        except Exception as e:
            result["error"] = str(e)
            result["available"] = None

        return result

    def check_domains(self, domains: List[str]) -> List[Dict[str, any]]:
        results = []

        domain_combinations = []
        for domain in domains:
            for tld in self.tlds_to_check:
                domain_combinations.append(domain + tld)

        max_workers = min(20, len(domain_combinations))

        with tqdm.tqdm(total=len(domain_combinations), desc="Checking domains") as pbar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_domain = {
                    executor.submit(self.check_domain_availability, domain): domain
                    for domain in domain_combinations
                }

                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append(
                            {
                                "domain": domain,
                                "available": None,
                                "error": str(e),
                                "registrar": None,
                                "expiration_date": None,
                            }
                        )
                    pbar.update(1)

        return results

    def run(self, prompt: str):
        domains_response = self.get_domains(prompt)
        results = self.check_domains(domains_response.domains)

        self._pretty_print_results(results)

    def _pretty_print_results(self, results: List[Dict[str, any]]):
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        results = sorted(
            results,
            key=lambda x: (
                x["domain"].split(".", 1)[0],
                x["domain"].split(".", 1)[1],
            ),
        )

        table_data = []

        for result in results:
            domain = result["domain"]
            available = result["available"]

            if available is True:
                status = f"{GREEN}Available{RESET}"
            elif available is False:
                status = f"{RED}Taken{RESET}"
            else:
                status = f"{YELLOW}Unknown{RESET}"

            table_data.append([domain, status])

        headers = ["Domain", "Status"]
        print(tabulate(table_data, headers=headers, tablefmt="simple"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", type=str)
    parser.add_argument(
        "--domains",
        nargs="*",
        required=False,
        default=None,
        help="List of TLDs to check (e.g., .com .ai .net)",
    )
    args = parser.parse_args()
    domain_searcher = DomainSearcher(args.domains)
    domain_searcher.run(args.prompt)
