# Take in prompt
# get list of strings from gpt
# for each string check if domains are available
# pretty print the results

import argparse
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

load_dotenv()


class Domains(BaseModel):
    domains: list[str] = Field(
        description="A list of potential domains", min_length=20, max_length=20
    )


class DomainSearcher:
    def __init__(self):
        self.client = OpenAI()
        self.tlds_to_check = [
            ".com",
            ".co",
            ".ai",
        ]

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
            # First, check if the domain has DNS records
            try:
                socket.gethostbyname(domain)
                # If we can resolve DNS, domain is likely taken
                result["available"] = False
            except socket.gaierror:
                # DNS lookup failed, might be available
                pass

            # Try WHOIS lookup for more detailed info
            w = whois.whois(domain)

            # If domain_name is None or empty, domain might be available
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
            # WHOIS lookup failed - domain might be available
            result["available"] = True
        except Exception as e:
            result["error"] = str(e)
            # If there's an error, we can't determine availability
            result["available"] = None

        return result

    def check_domains(self, domains: List[str]) -> List[Dict[str, any]]:
        results = []

        # Create a list of all domain combinations to check
        domain_combinations = []
        for domain in domains:
            for tld in self.tlds_to_check:
                domain_combinations.append(domain + tld)

        # Use ThreadPoolExecutor for parallel domain checking
        # Adjust max_workers based on your needs (10-20 is usually good for network I/O)
        max_workers = min(20, len(domain_combinations))

        with tqdm.tqdm(total=len(domain_combinations), desc="Checking domains") as pbar:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks to the executor
                future_to_domain = {
                    executor.submit(self.check_domain_availability, domain): domain
                    for domain in domain_combinations
                }

                # Process completed tasks as they finish
                for future in as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        # If there's an error, create an error result
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

        # Pretty print with tabulate
        self._pretty_print_results(results)

    def _pretty_print_results(self, results: List[Dict[str, any]]):
        """Simple pretty printing showing only domain and availability"""
        # ANSI color codes
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        # Prepare data for tabulate
        table_data = []

        for result in results:
            domain = result["domain"]
            available = result["available"]

            # Format availability status with colors
            if available is True:
                status = f"{GREEN}Available{RESET}"
            elif available is False:
                status = f"{RED}Taken{RESET}"
            else:
                status = f"{YELLOW}Unknown{RESET}"

            table_data.append([domain, status])

        # Print the table
        headers = ["Domain", "Status"]
        print(tabulate(table_data, headers=headers, tablefmt="simple"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("prompt", type=str)
    args = parser.parse_args()
    domain_searcher = DomainSearcher()
    domain_searcher.run(args.prompt)
